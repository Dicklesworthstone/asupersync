    use super::*;
    use crate::net::atp::protocol::frames::{FrameType, ProtocolVersion};

    #[test]
    fn test_transcript_deterministic() {
        // Create identical frames
        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        // Hash with two different hashers
        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame1);
        hasher1.update_frame(&frame2);

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame1);
        hasher2.update_frame(&frame2);

        // Should produce identical hashes
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_transcript_order_sensitive() {
        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        // Hash in different orders
        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame1);
        hasher1.update_frame(&frame2);

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame2);
        hasher2.update_frame(&frame1);

        // Should produce different hashes
        assert_ne!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_transcript_with_extensions() {
        let mut frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"test".to_vec(),
        )
        .unwrap();

        // Add extensions in non-sorted order
        frame.header.extensions.insert(3, b"ext3".to_vec());
        frame.header.extensions.insert(1, b"ext1".to_vec());
        frame.header.extensions.insert(2, b"ext2".to_vec());

        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame);

        // Create identical frame with different insertion order
        let mut frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"test".to_vec(),
        )
        .unwrap();

        frame2.header.extensions.insert(2, b"ext2".to_vec());
        frame2.header.extensions.insert(3, b"ext3".to_vec());
        frame2.header.extensions.insert(1, b"ext1".to_vec());

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame2);

        // Should produce identical hashes despite different insertion order
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_session_transcript() {
        let mut transcript = SessionTranscript::new();

        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        transcript.add_frame(&frame1);
        let checkpoint1 = transcript.checkpoint();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        transcript.add_frame(&frame2);
        let checkpoint2 = transcript.checkpoint();

        assert_eq!(checkpoint1.frame_count, 1);
        assert_eq!(checkpoint2.frame_count, 2);
        assert_ne!(checkpoint1.hash, checkpoint2.hash);
    }

    #[test]
    fn test_transcript_hash_hex() {
        let hash = TranscriptHash([0xab; 32]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));

        let parsed = TranscriptHash::from_hex(&hex).unwrap();
        assert_eq!(parsed, hash);
    }

    #[test]
    fn test_transcript_verifier() {
        let checkpoints = vec![
            TranscriptCheckpoint {
                hash: TranscriptHash([1; 32]),
                frame_count: 1,
            },
            TranscriptCheckpoint {
                hash: TranscriptHash([2; 32]),
                frame_count: 2,
            },
        ];

        let mut verifier = TranscriptVerifier::new(checkpoints.clone());

        // Verify correct sequence
        verifier.verify_checkpoint(&checkpoints[0]).unwrap();
        verifier.verify_checkpoint(&checkpoints[1]).unwrap();
        assert!(verifier.is_complete());

        // Test incorrect hash
        let mut bad_verifier = TranscriptVerifier::new(checkpoints.clone());
        let bad_checkpoint = TranscriptCheckpoint {
            hash: TranscriptHash([99; 32]),
            frame_count: 1,
        };

        assert!(bad_verifier.verify_checkpoint(&bad_checkpoint).is_err());
    }
