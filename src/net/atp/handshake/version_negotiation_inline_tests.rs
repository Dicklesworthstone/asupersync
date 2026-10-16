    use super::*;

    #[test]
    fn test_version_negotiation_packet_roundtrip() {
        let source_cid = Bytes::from_static(b"server_cid");
        let dest_cid = Bytes::from_static(b"client_cid");
        let supported_versions = vec![0x00000001, 0x12345678];

        let packet = VersionNegotiationPacket::new(
            source_cid.clone(),
            dest_cid.clone(),
            supported_versions.clone(),
        );

        let encoded = packet.encode().unwrap();
        let decoded = VersionNegotiationPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.source_cid, source_cid);
        assert_eq!(decoded.dest_cid, dest_cid);
        assert_eq!(decoded.supported_versions, supported_versions);
    }

    #[test]
    fn test_version_support_check() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![0x00000001, 0x12345678],
        );

        assert!(packet.supports_version(0x00000001));
        assert!(packet.supports_version(0x12345678));
        assert!(!packet.supports_version(0xabcdef00));
    }

    #[test]
    fn test_version_selection() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![0x00000001, 0x12345678],
        );

        // A server that lists the attempted version did not need negotiation.
        assert_eq!(packet.select_version(0x00000001), None);

        // Unsupported attempted versions select the best version supported locally.
        assert_eq!(packet.select_version(0xabcdef00), Some(0x00000001));

        let unsupported_only = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![0x12345678],
        );
        assert_eq!(unsupported_only.select_version(0xabcdef00), None);
    }

    #[test]
    fn test_negotiation_needed() {
        let server_versions = vec![0x00000001, 0x12345678];

        assert!(!VersionNegotiation::is_negotiation_needed(
            0x00000001,
            &server_versions
        ));
        assert!(VersionNegotiation::is_negotiation_needed(
            0xabcdef00,
            &server_versions
        ));
    }

    #[test]
    fn test_invalid_packet_decode() {
        // Too short
        let result = VersionNegotiationPacket::decode(&[0x80, 0x00]);
        assert!(result.is_err());

        // Short header (not long header)
        let result = VersionNegotiationPacket::decode(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());

        // Non-zero version
        let result = VersionNegotiationPacket::decode(&[0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_zero_rejected_in_supported_versions() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![VERSION_NEGOTIATION_MARKER],
        );
        assert!(packet.encode().is_err());

        let encoded_with_zero = [
            0x80, 0, 0, 0, 0, // Long header, Version Negotiation marker
            0, // Empty destination CID
            0, // Empty source CID
            0, 0, 0, 0, // Invalid supported version 0
        ];
        assert!(VersionNegotiationPacket::decode(&encoded_with_zero).is_err());
    }

    #[test]
    fn test_validate_server_response_discards_attempted_version() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"original_dest"),
            Bytes::from_static(b"original_source"),
            vec![QuicVersion::V1 as u32],
        );

        let result = VersionNegotiation::validate_server_response(
            &packet,
            b"original_dest",
            b"original_source",
            QuicVersion::V1 as u32,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_response_accepts_supported_alternative() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"original_dest"),
            Bytes::from_static(b"original_source"),
            vec![QuicVersion::V1 as u32],
        );

        let result = VersionNegotiation::validate_server_response(
            &packet,
            b"original_dest",
            b"original_source",
            0xabcdef00,
        );

        assert!(result.is_ok());
    }
