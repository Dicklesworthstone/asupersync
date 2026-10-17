    use super::*;

    #[test]
    fn test_piece_id_ordering() {
        let piece1 = PieceId::new(1);
        let piece2 = PieceId::new(2);
        let piece3 = PieceId::new(1);

        assert!(piece1 < piece2);
        assert_eq!(piece1, piece3);
        assert_ne!(piece1, piece2);
    }

    #[test]
    fn test_swarm_config_defaults() {
        let config = SwarmConfig::default();

        assert_eq!(config.max_peers, 8);
        assert_eq!(
            config.piece_selection_strategy,
            PieceSelectionStrategy::RarestFirst
        );
        assert_eq!(config.peer_quality_threshold, 0.5);
        assert!(config.enable_incentives);
    }

    #[test]
    fn test_peer_capabilities_defaults() {
        let capabilities = PeerCapabilities::default();

        assert_eq!(capabilities.max_concurrent_uploads, 4);
        assert_eq!(capabilities.preferred_chunk_size, 1024 * 1024);
        assert!(capabilities.participates_in_incentives);
        assert!(!capabilities.supports_repair_symbols);
    }

    #[test]
    fn test_piece_assignment_serialization() {
        let assignment = PieceAssignment {
            peer_id: PeerId::new("test-peer"),
            piece_id: PieceId::new(42),
            priority: 100,
            estimated_completion: swarm_time_now(),
            retry_count: 0,
            assigned_at: swarm_time_now(),
        };

        let serialized = serde_json::to_string(&assignment).unwrap();
        let deserialized: PieceAssignment = serde_json::from_str(&serialized).unwrap();

        assert_eq!(assignment.piece_id, deserialized.piece_id);
        assert_eq!(assignment.priority, deserialized.priority);
        assert_eq!(assignment.retry_count, deserialized.retry_count);
    }

    #[test]
    fn test_swarm_error_display() {
        let error = SwarmError::PeerQualityBelowThreshold {
            peer_id: PeerId::new("bad-peer"),
            quality: 0.3,
            threshold: 0.5,
        };

        let display = format!("{}", error);
        assert!(display.contains("Peer quality below threshold"));
        assert!(display.contains("bad-peer"));
        assert!(display.contains("0.3"));
        assert!(display.contains("0.5"));
    }

    #[test]
    fn test_swarm_event_serialization() {
        let event = SwarmEvent::PeerJoined {
            peer_id: PeerId::new("new-peer"),
            available_pieces: [PieceId::new(1), PieceId::new(2)].iter().copied().collect(),
            capabilities: PeerCapabilities::default(),
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: SwarmEvent = serde_json::from_str(&serialized).unwrap();

        match (event, deserialized) {
            (
                SwarmEvent::PeerJoined {
                    available_pieces: p1,
                    ..
                },
                SwarmEvent::PeerJoined {
                    available_pieces: p2,
                    ..
                },
            ) => {
                assert_eq!(p1, p2);
            }
            _ => panic!("Event type mismatch after serialization"),
        }
    }
