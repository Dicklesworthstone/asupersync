    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        let frame_types = [
            FrameType::Handshake,
            FrameType::HandshakeAck,
            FrameType::Capabilities,
            FrameType::ObjectManifest,
            FrameType::ObjectData,
            FrameType::PathUpdate,
            FrameType::Cancel,
            FrameType::Error,
            FrameType::Close,
        ];

        for frame_type in frame_types {
            let varint = frame_type.to_varint();
            let parsed = FrameType::from_varint(varint).unwrap();
            assert_eq!(parsed, frame_type);
        }
    }

    #[test]
    fn test_frame_creation() {
        let payload = b"Hello, ATP!".to_vec();
        let frame = Frame::new(ProtocolVersion::V0, FrameType::Handshake, payload.clone()).unwrap();

        assert_eq!(frame.version(), ProtocolVersion::V0);
        assert_eq!(frame.frame_type(), FrameType::Handshake);
        assert_eq!(frame.payload(), payload);
    }

    #[test]
    fn test_frame_header_with_extensions() {
        let header = FrameHeader::new(ProtocolVersion::V0, FrameType::Capabilities, 100)
            .unwrap()
            .with_extension(1, b"ext1".to_vec())
            .with_extension(2, b"extension2".to_vec());

        assert_eq!(header.extensions.len(), 2);
        assert_eq!(header.extensions[&1], b"ext1");
        assert_eq!(header.extensions[&2], b"extension2");
    }

    #[test]
    fn frame_empty_uses_protocol_wire_bytes_not_marker_payloads() {
        let frame = Frame::empty(FrameType::Control).unwrap();

        assert_eq!(frame.payload(), b"");

        assert_eq!(
            frame.to_wire_bytes().unwrap(),
            vec![0x00, 0x44, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_protocol_version_display() {
        assert_eq!(ProtocolVersion::V0.to_string(), "ATP/0");
        assert_eq!(ProtocolVersion(42).to_string(), "ATP/42");
    }
