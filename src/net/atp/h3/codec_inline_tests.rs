    use super::*;
    use crate::net::atp::protocol::ProtocolVersion;

    #[test]
    fn test_webtransport_frame_type_conversion() {
        assert_eq!(
            WebTransportFrameType::from_atp_frame_type(FrameType::Control).unwrap(),
            WebTransportFrameType::Control
        );

        assert_eq!(
            WebTransportFrameType::Data.to_atp_frame_type(),
            FrameType::Data
        );
    }

    #[test]
    fn test_codec_creation() {
        let codec = H3FrameCodec::new();
        assert_eq!(codec.max_frame_size(), 64 * 1024);

        let codec = H3FrameCodec::with_max_frame_size(1024);
        assert_eq!(codec.max_frame_size(), 1024);
    }

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let codec = H3FrameCodec::new();

        let frame = AtpFrame::new(
            ProtocolVersion::CURRENT,
            FrameType::Control,
            b"control payload".to_vec(),
        )
        .unwrap();
        let encoded = codec.encode_atp_frame(&frame).unwrap();

        // Verify frame structure: type + length + payload
        assert!(encoded.len() >= 5);
        assert_eq!(encoded[0], WebTransportFrameType::Control as u8);

        // Test decoding
        let decoded = codec.decode_atp_frame(&encoded).unwrap();
        assert_eq!(decoded.frame_type(), FrameType::Control);
        assert_eq!(decoded.payload(), b"control payload");
    }

    #[test]
    fn test_frame_size_limits() {
        let mut codec = H3FrameCodec::with_max_frame_size(100);

        // Frame that would exceed limit should fail
        codec.set_max_frame_size(5); // Very small limit

        let frame = AtpFrame::new(
            ProtocolVersion::CURRENT,
            FrameType::Data,
            b"payload-too-large-for-limit".to_vec(),
        )
        .unwrap();
        let result = codec.encode_atp_frame(&frame);
        assert!(result.is_err());

        if let Err(AtpH3Error::Codec(msg)) = result {
            assert!(msg.contains("exceeds maximum"));
        }
    }

    #[test]
    fn test_invalid_frame_decode() {
        let codec = H3FrameCodec::new();

        // Too short
        assert!(codec.decode_atp_frame(&[0x01]).is_err());

        // Invalid frame type
        let invalid_frame = vec![0xFF, 0x00, 0x00, 0x00, 0x01, 0x42];
        assert!(codec.decode_atp_frame(&invalid_frame).is_err());

        // Truncated frame
        let truncated_frame = vec![0x01, 0x00, 0x00, 0x00, 0x10]; // Claims 16 bytes but only has header
        assert!(codec.decode_atp_frame(&truncated_frame).is_err());
    }

    #[test]
    fn test_oversized_declared_length_rejected_before_payload_read() {
        let codec = H3FrameCodec::with_max_frame_size(4);
        let oversized_frame = vec![0x01, 0x00, 0x00, 0x00, 0x05];

        let err = codec
            .decode_atp_frame(&oversized_frame)
            .expect_err("oversized declared length should fail");

        assert!(matches!(err, AtpH3Error::Codec(message) if message.contains("Frame too large")));
    }

    #[test]
    fn test_mismatched_outer_and_inner_frame_type_rejected() {
        let codec = H3FrameCodec::new();
        let frame =
            AtpFrame::new(ProtocolVersion::CURRENT, FrameType::Data, b"data".to_vec()).unwrap();
        let mut encoded = codec.encode_atp_frame(&frame).unwrap();
        encoded[0] = WebTransportFrameType::Control as u8;

        let err = codec.decode_atp_frame(&encoded).unwrap_err();
        assert!(matches!(err, AtpH3Error::Codec(message) if message.contains("does not match")));
    }
