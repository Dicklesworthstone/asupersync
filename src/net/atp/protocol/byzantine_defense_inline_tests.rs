    use super::*;
    use crate::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};

    fn nonzero_bytes(value: u8, len: usize) -> Vec<u8> {
        vec![value; len]
    }

    fn object_request_frame() -> Frame {
        Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            nonzero_bytes(7, DIGEST_LEN),
        )
        .expect("valid object request frame")
    }

    fn manifest_frame(manifest_size: usize) -> Frame {
        let mut payload = Vec::new();
        let mut version = BytesMut::new();
        VarInt::new(ManifestVersion::CURRENT.0.into())
            .expect("manifest version fits varint")
            .encode(&mut version)
            .expect("encode manifest version");
        payload.extend_from_slice(&version);
        payload.extend_from_slice(&(manifest_size as u64).to_be_bytes());
        payload.extend(std::iter::repeat_n(0x5a, manifest_size));
        Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectManifest, payload)
            .expect("valid manifest frame")
    }

    fn handshake_frame() -> Frame {
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonzero_bytes(1, PEER_ID_LEN));
        payload.extend_from_slice(&nonzero_bytes(2, PEER_ID_LEN));
        payload.extend_from_slice(&nonzero_bytes(3, TRANSFER_NONCE_LEN));
        payload.extend_from_slice(&ProtocolVersion::CURRENT.0.to_be_bytes());
        payload.push(0); // no manifest root
        payload.push(0); // no path id
        payload.push(0); // no relay peer
        payload.push(0); // direct context
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.push(3); // encryption_policy
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        Frame::new(ProtocolVersion::CURRENT, FrameType::Handshake, payload)
            .expect("valid handshake frame")
    }

    fn create_test_frame(frame_type: FrameType, payload: Vec<u8>) -> Frame {
        Frame::new(ProtocolVersion::CURRENT, frame_type, payload).expect("valid test frame")
    }

    #[test]
    fn test_frame_rate_limiting() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("rate-limited-peer");

        // Modify limits to be more restrictive for testing
        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_frame_rate: 2,
                rate_limit_window: 1,
                ..Default::default()
            },
        );

        let frame = object_request_frame();

        // Should allow first two frames
        assert!(processor.process_frame(peer_id, &frame).is_ok());
        assert!(processor.process_frame(peer_id, &frame).is_ok());

        // Should reject third frame due to rate limit
        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::FrameRateLimited { .. })
        ));
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("memory-limited-peer");

        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_memory_per_peer: 64,
                max_manifest_size: 1024,
                ..Default::default()
            },
        );

        let large_frame = manifest_frame(128);

        // Should reject frame due to memory limits
        assert!(matches!(
            processor.process_frame(peer_id, &large_frame),
            Err(ByzantineDefenseError::ResourceLimitExceeded(
                ResourceError::MemoryLimitExceeded { .. }
            ))
        ));
    }

    #[test]
    fn manifest_size_cap_rejects_before_memory_allocation() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("oversized-manifest-peer");

        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_memory_per_peer: 24,
                max_manifest_size: 16,
                ..Default::default()
            },
        );

        let frame = manifest_frame(32);

        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::ResourceLimitExceeded(
                ResourceError::ManifestSizeExceeded {
                    size: 32,
                    limit: 16
                }
            ))
        ));

        let usage = processor
            .resource_manager
            .peer_usage(&peer_id)
            .expect("rate-limit history keeps peer visible after rejection");
        assert_eq!(usage.memory_usage, 0);
        assert_eq!(usage.pending_frames, 0);
        assert_eq!(usage.recent_frame_count, 1);
    }

    #[test]
    fn test_session_limits() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("session-limited-peer");

        // Modify limits to allow only one session
        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_sessions_per_peer: 1,
                ..Default::default()
            },
        );

        let handshake_frame = handshake_frame();

        // Should allow first session
        assert!(processor.process_frame(peer_id, &handshake_frame).is_ok());

        // Should reject second session
        assert!(matches!(
            processor.process_frame(peer_id, &handshake_frame),
            Err(ByzantineDefenseError::SessionLimited { .. })
        ));
    }

    #[test]
    fn test_resource_cleanup() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("cleanup-peer");

        let frame = object_request_frame();

        // Process frame successfully
        assert!(processor.process_frame(peer_id, &frame).is_ok());

        // Clean up the session
        processor.handle_session_end(&peer_id);
        processor.handle_request_completion(&peer_id);

        // Run maintenance
        processor.maintain();

        // `maintain` preserves recent rate-limit history so a just-active peer
        // cannot immediately reset its admission window by finishing work. The
        // cleanup invariant here is that all outstanding resources are released.
        let usage = processor
            .resource_manager
            .peer_usage(&peer_id)
            .expect("recent peer history is retained");
        assert_eq!(usage.memory_usage, 0);
        assert_eq!(usage.pending_frames, 0);
        assert_eq!(usage.active_sessions, 0);
        assert_eq!(usage.pending_requests, 0);
        assert_eq!(usage.recent_frame_count, 1);

        let stats = processor.resource_stats();
        assert_eq!(stats.peer_count, 1);

        // Immediate removal is still available through the explicit force-cleanup path.
        processor.force_cleanup_peer(&peer_id);
        let stats = processor.resource_stats();
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn capabilities_ack_rejects_empty_payload() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("capabilities-ack-peer");
        let frame = create_test_frame(FrameType::CapabilitiesAck, Vec::new());

        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::RequestRejected { .. })
        ));
    }

    #[test]
    fn path_challenge_requires_exact_nonzero_eight_bytes() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("path-challenge-peer");
        let short = create_test_frame(FrameType::PathChallenge, vec![1; 7]);
        let zero = create_test_frame(FrameType::PathChallenge, vec![0; 8]);
        let valid = create_test_frame(FrameType::PathChallenge, 9u64.to_be_bytes().to_vec());

        assert!(processor.process_frame(peer_id, &short).is_err());
        assert!(processor.process_frame(peer_id, &zero).is_err());
        assert!(processor.process_frame(peer_id, &valid).is_ok());
    }

    #[test]
    fn object_request_requires_nonzero_object_id() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("object-request-peer");
        let bad = create_test_frame(FrameType::ObjectRequest, vec![0; DIGEST_LEN]);
        let good = object_request_frame();

        assert!(processor.process_frame(peer_id, &bad).is_err());
        assert!(processor.process_frame(peer_id, &good).is_ok());
    }

    #[test]
    fn object_error_requires_code_and_utf8_reason() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("object-error-peer");
        let mut payload = nonzero_bytes(11, DIGEST_LEN);
        payload.extend_from_slice(&7u32.to_be_bytes());
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(b"lost");
        let valid = create_test_frame(FrameType::ObjectError, payload);

        let mut invalid_utf8 = nonzero_bytes(11, DIGEST_LEN);
        invalid_utf8.extend_from_slice(&7u32.to_be_bytes());
        invalid_utf8.extend_from_slice(&1u32.to_be_bytes());
        invalid_utf8.push(0xff);
        let invalid = create_test_frame(FrameType::ObjectError, invalid_utf8);

        assert!(processor.process_frame(peer_id, &valid).is_ok());
        assert!(processor.process_frame(peer_id, &invalid).is_err());
    }

    #[test]
    fn manifest_rejects_declared_size_mismatch() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("manifest-peer");
        let mut payload = Vec::new();
        payload.push(ManifestVersion::CURRENT.0 as u8);
        payload.extend_from_slice(&8u64.to_be_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        let frame = create_test_frame(FrameType::ObjectManifest, payload);

        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::RequestRejected { .. })
        ));
    }
