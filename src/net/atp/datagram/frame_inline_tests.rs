    use super::*;

    #[test]
    fn test_datagram_frame_without_length() {
        let payload = Bytes::from_static(b"hello datagram");
        let frame = DatagramFrame::without_length(payload.clone());

        assert_eq!(frame.frame_type, DatagramFrameType::Datagram);
        assert_eq!(frame.payload(), &payload);
        assert!(!frame.has_length_field());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.clone();
        let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();

        assert_eq!(decoded.frame_type, DatagramFrameType::Datagram);
        assert_eq!(decoded.payload(), &payload);
    }

    #[test]
    fn test_datagram_frame_with_length() {
        let payload = Bytes::from_static(b"hello datagram with length");
        let frame = DatagramFrame::with_length(payload.clone());

        assert_eq!(frame.frame_type, DatagramFrameType::DatagramWithLength);
        assert_eq!(frame.payload(), &payload);
        assert!(frame.has_length_field());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.clone();
        let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();

        assert_eq!(decoded.frame_type, DatagramFrameType::DatagramWithLength);
        assert_eq!(decoded.payload(), &payload);
    }

    #[test]
    fn test_datagram_size_limits() {
        let large_payload = Bytes::from(vec![0u8; 2048]);
        let frame = DatagramFrame::with_length(large_payload);

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf;
        let result = DatagramFrame::decode(&mut decode_buf, 1024);

        assert!(matches!(
            result,
            Outcome::Err(DatagramError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_datagram_metadata() {
        let mut metadata = DatagramMetadata::new("path_probe")
            .with_priority(DatagramPriority::High)
            .with_correlation_id(42)
            .with_path_id(1);

        assert_eq!(metadata.priority, DatagramPriority::High);
        assert_eq!(metadata.correlation_id, Some(42));
        assert_eq!(metadata.path_id, Some(1));
        assert_eq!(metadata.payload_class, "path_probe");

        // Test expiration
        assert!(!metadata.is_expired());

        metadata = metadata.with_expiration(
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("test instant should support one-second subtraction"),
        );
        assert!(metadata.is_expired());
    }

    #[test]
    fn test_frame_type_conversion() {
        let datagram = DatagramFrameType::Datagram;
        let datagram_with_length = DatagramFrameType::DatagramWithLength;

        assert_eq!(
            DatagramFrameType::from_varint(datagram.to_varint()),
            Some(datagram)
        );
        assert_eq!(
            DatagramFrameType::from_varint(datagram_with_length.to_varint()),
            Some(datagram_with_length)
        );
        assert_eq!(
            DatagramFrameType::from_varint(VarInt::new(0x99).unwrap()),
            None
        );
    }

    #[test]
    fn test_invalid_frame_decode() {
        // Empty buffer
        let mut empty_buf = BytesMut::new();
        let result = DatagramFrame::decode(&mut empty_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));

        // Unknown frame type
        let mut bad_type_buf = BytesMut::new();
        VarInt::new(0x99)
            .unwrap()
            .encode(&mut bad_type_buf)
            .unwrap();
        let result = DatagramFrame::decode(&mut bad_type_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));

        // Truncated length field
        let mut truncated_buf = BytesMut::new();
        VarInt::new(0x31)
            .unwrap()
            .encode(&mut truncated_buf)
            .unwrap(); // DatagramWithLength
        let result = DatagramFrame::decode(&mut truncated_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(DatagramPriority::High > DatagramPriority::Normal);
        assert!(DatagramPriority::Normal > DatagramPriority::Low);
        assert!(DatagramPriority::Low > DatagramPriority::Background);
    }
