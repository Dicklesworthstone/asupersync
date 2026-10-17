    use super::*;
    use crate::atp::swarm::PeerCapabilities;
    use std::collections::BTreeSet;

    fn create_test_peer(id: &str, quality_score: f64, download_speed: f64) -> SwarmPeer {
        SwarmPeer {
            peer_id: PeerId::new(id),
            endpoint: "127.0.0.1:8080".parse().unwrap(),
            available_pieces: BTreeSet::new(),
            quality: PeerQuality {
                overall_score: quality_score,
                download_speed,
                ..Default::default()
            },
            reputation: PeerReputation::default(),
            last_seen: swarm_time_now(),
            pending_requests: BTreeSet::new(),
            capabilities: PeerCapabilities::default(),
        }
    }

    #[test]
    fn test_peer_selector_creation() {
        let selector = PeerSelector::new();
        assert_eq!(selector.quality_history.len(), 0);
    }

    #[test]
    fn test_select_peer_capacity_counts_load_once() {
        // Regression: capacity must be judged by `active_loads` alone.
        // `pending_requests` tracks the same in-flight requests as
        // `active_loads`; summing both double-counted and (with default
        // max_concurrent_uploads=4) excluded any peer at 2 real requests,
        // stalling transfers larger than 2 * peer_count pieces.
        let selector = PeerSelector::new();
        let piece = PieceId::new(7);

        let mut peer = create_test_peer("peer1", 0.9, 1_000_000.0);
        peer.available_pieces.insert(piece);
        // 3 in-flight requests, mirrored into pending_requests (the old
        // double-count source). Real load is 3 < max(4) → still selectable.
        peer.pending_requests.insert(PieceId::new(1));
        peer.pending_requests.insert(PieceId::new(2));
        peer.pending_requests.insert(PieceId::new(3));

        let mut peers = HashMap::new();
        peers.insert(peer.peer_id.clone(), peer.clone());
        let mut loads = HashMap::new();
        loads.insert(peer.peer_id.clone(), 3usize);

        assert!(
            selector
                .select_peer_for_piece(&piece, &peers, &loads)
                .is_ok(),
            "peer at 3 real requests (max 4) must remain selectable"
        );

        // At the real capacity limit it must be excluded.
        loads.insert(peer.peer_id.clone(), 4usize);
        assert!(
            selector
                .select_peer_for_piece(&piece, &peers, &loads)
                .is_err(),
            "peer at the concurrency limit must be excluded"
        );
    }

    #[test]
    fn test_select_peers_empty_candidates() {
        let selector = PeerSelector::new();
        let result = selector.select_peers(&[], 5, 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_peers_quality_filtering() {
        let selector = PeerSelector::new();
        let candidates = vec![
            create_test_peer("peer1", 0.8, 1000000.0),
            create_test_peer("peer2", 0.3, 500000.0), // Below threshold
            create_test_peer("peer3", 0.7, 2000000.0),
        ];

        let selected = selector.select_peers(&candidates, 5, 0.5).unwrap();
        assert_eq!(selected.len(), 2);

        let selected_ids: Vec<_> = selected.iter().map(|p| p.peer_id.as_str()).collect();
        assert!(selected_ids.contains(&"peer1"));
        assert!(selected_ids.contains(&"peer3"));
        assert!(!selected_ids.contains(&"peer2"));
    }

    #[test]
    fn test_select_peers_max_limit() {
        let selector = PeerSelector::new();
        let candidates = vec![
            create_test_peer("peer1", 0.9, 1000000.0),
            create_test_peer("peer2", 0.8, 1500000.0),
            create_test_peer("peer3", 0.7, 2000000.0),
        ];

        let selected = selector.select_peers(&candidates, 2, 0.5).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_calculate_peer_score() {
        let selector = PeerSelector::new();
        let peer = create_test_peer("test", 0.8, 5000000.0);

        let score = selector.calculate_peer_score(&peer);
        assert!(score.composite_score > 0.0);
        assert!(score.composite_score <= 1.0);
        assert!(score.speed_score > 0.0);
        assert!(score.reliability_score > 0.0);
    }

    #[test]
    fn test_update_peer_quality() {
        let mut selector = PeerSelector::new();
        let peer_id = PeerId::new("test-peer");

        selector.update_peer_quality(&peer_id, 1_000_000.0, Duration::from_millis(100), true);

        let history = selector.get_quality_history(&peer_id).unwrap();
        assert_eq!(history.evaluations.len(), 1);
        assert_eq!(history.successful_transfers, 1);
        assert_eq!(history.failed_transfers, 0);
    }

    #[test]
    fn test_cleanup_old_data() {
        let mut selector = PeerSelector::with_config(PeerSelectionConfig {
            max_evaluation_age: Duration::from_millis(100),
            ..Default::default()
        });

        let peer_id = PeerId::new("test-peer");

        selector.update_peer_quality(&peer_id, 1_000_000.0, Duration::from_millis(100), true);

        // Wait for data to become old
        std::thread::sleep(Duration::from_millis(200));

        selector.cleanup_old_data();

        // History should be cleaned up
        assert!(selector.get_quality_history(&peer_id).is_none());
    }
